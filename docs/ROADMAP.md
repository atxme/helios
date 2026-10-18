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
| VIP non réconciliée | Écart supposé avec `data_plane.rs` | `README.md` dit que l'adresse de `network.toml` fait autorité, comme le code. La discordance avec ADR-001 §4 reste traitée par D3 |
| `from_peers(&[])` (ancien D4) | Table de pairs vide à l'enrôlement | Supprimé avec l'IPAM unifié (`26ac509`, 1er octobre) ; CRATE-REORGANIZATION §13.4 mis à jour |

Les mentions prospectives de macOS (Keychain, cible Orion) ont été retirées
d'ADR-001, ADR-005 et ADR-006 le 18 octobre ; les mentions historiques de
l'ère IKEv2 restent.

## 3. Horizon 1 : validation sur cible

C'est ce qui sépare « implémenté » de « livrable ». Ordre proposé : d'abord ce
qui peut invalider une conception, ensuite ce qui valide du code existant.

| # | Essai | Source | Faisable ici ? |
| --- | --- | --- | --- |
| V1 | **Renouvellement de PSK à chaud avec trafic actif**, via « Renouveler la clé maintenant », noyau Linux **et** WireGuard-NT, chemin sain puis dégradé | v5 §20.0, §12.3, `testing/TESTING.md` | **Non** : matériel requis (gateway physique, WAN réel) et cible requise (WireGuard-NT sur Windows) |
| V2 | Banc netns reproductible (T22) | ETUDE-IPV6 T22 | **Oui** : pas de matériel, prépare V3 à V5 |
| V3 | Campagne v5 §20.2 : pose des slots, redémarrage `heliosd`, arrêt brutal client, `release` dans le tunnel, coupure WAN > 35 s et > 5 min | v5 §20.2 | **Non** : matériel requis (coupure WAN réelle) |
| V4 | Campagne IPv6 (T23) et VM Windows (T01, T02, T18, T19) | ETUDE-IPV6 | **Non** : cible Windows et réseau réel |
| V5 | Recette firewall : MSS, ICMPv6 PTB hors flux suivi, ND/RA/DHCPv6, atomicité | FIREWALL-V2 « Validation sur cible » | **Non** : cible requise (noyau Linux réel) |
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
| D2 | Texte d'ADR-001 §3 bis après T01 (`::/0`) | ETUDE-IPV6 T01 | clôture de la fuite IPv6 côté ADR |
| D3 | ADR-001 §4 et ADR-004 §5 contredisent l'IPAM unifié (à confirmer contre le code) | ETUDE-IPV6 T11 + T14 | mise en conformité ADR ↔ code |
| D5 | **DNS des clients** non tunnelé, même avec `allow_client_internet` | README, `helios-firewall/src/ruleset.rs`, ADR-006 | confidentialité des noms résolus (F7) |
| D6 | Activation de l'anti-spoof `fib` en multi-uplink / policy routing | FIREWALL-V2 « Capacités » | encodeur déjà livré |
| D7 | Acceptation ICMPv6 Packet Too Big scopée par interface | FIREWALL-V2, ETUDE-IPV6 §9.1 | après observation V5 |
| D8 | Authentification de `POST /v1/campaigns` sur l'origine publique | ROTATION-CERTIFICATS §11.6, §12.5 | boutons de campagne dans la console ; aujourd'hui volontairement refusé |
| D9 | Certificat EV Authenticode : achat et token de signature | ADR-004 « Limites connues » | réputation SmartScreen ; **matériel requis** pour la signature, décision de coût |

## 5. Horizon 3 : fonctionnalités

Classées par dépendance, pas par taille. La colonne « Faisable ici » indique
si le travail se fait entièrement depuis le dépôt ; une validation sur cible
reste alors à faire à part.

### Protocole et sécurité

| # | Fonctionnalité | Source | Dépend de | Faisable ici ? |
| --- | --- | --- | --- | --- |
| F1 | **Renouvellement de PSK en place** dans le tunnel, à 80 % de 24 h ou de 100 Gio. **Fusionné dans `main` le 18 octobre 2026.** | v5 §7.6, §12.3 ; `docs/superpowers/specs/2026-10-09-renouvellement-psk-design.md` | V1 pour la mesure | Code : fait. Mesure : V1 |
| F2 | **Enrôlement sans transport de clé privée** et signature opérateur ; `helios enroll` distribue encore l'identité cliente comme en v4 | v5 §15 | : | **Oui** |
| F3 | État terminal `revoked` porté par le même sérialiseur que le slot, génération incrémentée | v5 §11.1 | : | **Oui** |
| F4 | Retrait de la variante `classic` de `ProtectionMode` : migration de `network.toml` et de l'octet `mode_id = 0` du manifeste de coffre | v5 §19 | : | **Oui** |
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
| F10 | Forwarding IPv6 choisi explicitement (phase 4) | ETUDE-IPV6 | V4, D2 | Code : **oui** ; validation : **non** (cible) |

### Plateforme Orion

| # | Fonctionnalité | Source | Dépend de | Faisable ici ? |
| --- | --- | --- | --- | --- |
| F11 | **Séparation des privilèges Windows** : service privilégié, IPC authentifié, politique d'autorisation, pour retirer `requireAdministrator` de l'IHM | ADR-004 « Limites connues » | conception et audit conjoints | Conception : **oui** ; validation : **non** (Windows réel) |
| F12 | **Stockage protégé Linux** (`libsecret`) : refus explicite actuel conservé d'ici là. macOS retiré du périmètre. | ADR-005, ADR-006 | : | Code : **oui** ; validation : session Linux de bureau, **non** depuis WSL2 |
| F13 | Association `.orion` pour le paquet NSIS | ORION-DISTRIBUTION | : | Code : **oui** ; validation : **non** (Windows réel) |
| F14 | Parité Orion des cérémonies Astra encore portées par `astra-signer` | ADR-008 | : | **Oui** |

Pour F11, le client WireGuard Windows officiel est un modèle éprouvé : un
service gestionnaire SYSTEM qui démarre un service par tunnel, une IHM non
privilégiée héritant de tubes anonymes, et un tube nommé de tunnel dont le
propriétaire est vérifié avant connexion. Son propre document de surface
d'attaque signale la conservation de `SeLoadDriverPrivilege` comme point faible :
à ne pas reproduire.

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
| T5 | Réorganisation des crates : `impl RenewalSession` (DEFERRED), `orion-core/src/backend/mod.rs`, `helios-api` `certificates.rs`/`routes.rs`, réalignement de `ruleset/tests/` | CRATE-REORGANIZATION §13 | lots atomiques avec golden avant découpage | **Oui** |
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
  V2 banc netns · outillage headless Orion · T2 · T4 compilation · T5 · T6 mesure
  D1, D2, D3, D5 à D8 arbitrages · F2 enrôlement · F3 revoked · F4 retrait classic
  F6 nomade · F8 limit · F14 Astra · F15 reproductible

Faisable en code, validation sur cible à planifier
  F5 (après D1) · F7 (après D5) · F11 conception · F12 libsecret · F13 NSIS

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

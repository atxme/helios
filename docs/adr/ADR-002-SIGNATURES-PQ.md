# ADR 002 — Signatures post-quantiques des artefacts de confiance

**Statut** : **accepté** (2026-07-19) — choix techniques figés, voir « Choix arrêtés »
**Portée** : signature du billet de rescellement, du fichier de récupération de
la clé WireGuard et des manifestes de binaires Helios. Ne concerne pas l'échange de
clés (ADR-001 §2, déjà post-quantique via ML-KEM-1024).

## État d’implémentation au 2026-07-19

| Lot | État | Preuve principale |
|---|---|---|
| Enveloppe hybride et trousseau | fait | `aether::sig`, tests anti-downgrade et Ed25519 strict |
| Billet TPM v2 | fait | `helio-tpm::reseal_ticket`, rupture v1 sans fallback |
| Récupération WireGuard | bloqué | arbitrage compteur fichier / NV TPM requis |
| Outil éditeur | fait | `helios-publisher`, auto-vérification et tests CLI |

`GET /api/trust` expose la politique et les empreintes réellement compilées.
Un build release sans `HELIOS_PUBLISHER_KEYRING_PATH` est refusé.

## Contexte

Deux artefacts autorisent aujourd'hui des opérations critiques sur la gateway :

| Artefact | Ce qu'il autorise | Signature actuelle |
|---|---|---|
| Billet de rescellement | Rescelle le secret TPM après changement de PCR | Ed25519 |
| Fichier de récupération | **Injecte l'identité WireGuard** de la gateway | **aucune** |

Le second est le plus sensible : il pose la clé privée qui authentifie chaque
handshake. Non signé, un attaquant capable d'écrire sur la partition de
configuration y dépose une clé qu'il contrôle, et la gateway l'adopte au
démarrage suivant.

## Pourquoi du post-quantique ici — et pourquoi ce n'est pas évident

Une signature n'est **pas** exposée au *harvest-now-decrypt-later*. Forger une
signature en 2035 ne rejoue rien de 2026 : l'urgence qui justifie ML-KEM pour
l'échange de clés ne s'applique pas telle quelle.

L'argument est ailleurs, et il est spécifique à cet objet : **le vérificateur vit
très longtemps**. La clé publique de l'éditeur est ancrée dans une appliance
déployée pour dix à quinze ans. Le jour où un calculateur quantique
cryptographiquement pertinent existe, il ne déchiffre pas le passé — il **forge
des billets et des fichiers de récupération** pour tout le parc encore en
service. C'est exactement le raisonnement qui fait recommander les signatures PQ
pour le *firmware signing* (NIST SP 800-208), et il s'applique ici sans réserve.

Autrement dit : PQ pour l'échange de clés protège le **passé**, PQ pour les
signatures protège la **durée de vie du matériel**.

## Décisions proposées

### 1. Hybride Ed25519 + ML-DSA-65, les deux obligatoires

Pas de PQ seul. Deux raisons convergentes :

* La position PQC publiée de l'**ANSSI** impose l'hybridation et déconseille le
  PQ seul avant ~2030 — les implémentations sont jeunes. Le projet est déjà sur
  cette ligne pour l'échange de clés.
* ML-DSA est un schéma récent. Un hybride survit à la rupture de **l'un** des
  deux, quel qu'il soit.

**Règle de vérification : les deux signatures doivent être valides. Jamais « au
moins une ».** Un `OU` laisserait le schéma le plus faible décider seul.

### 2. Le format doit résister au *downgrade*

C'est le point où ce genre de conception échoue le plus souvent. L'enveloppe
porte une liste de signatures, et le vérificateur détient une **liste d'algorithmes
exigés, en dur dans le binaire** :

```jsonc
{
  "payload":   { /* contenu métier, sérialisé canoniquement */ },
  "key_epoch": 1,                     // génération de clés éditeur
  "signatures": [
    { "alg": "ed25519",   "sig": "…" },
    { "alg": "ml-dsa-65", "sig": "…" }
  ]
}
```

Vérification :

1. pour **chaque** algorithme de la liste exigée, une signature valide doit être
   présente — l'absence est un rejet, pas une tolérance ;
2. les algorithmes inconnus supplémentaires sont ignorés (compatibilité avant) ;
3. une signature présente mais invalide est un rejet, même si les autres passent.

Sans la règle 1, un attaquant retire la signature ML-DSA et l'artefact reste
accepté sur la seule Ed25519 : tout le bénéfice disparaît.

### 3. Les octets signés sont canoniques et séparés par domaine

Le code actuel a déjà le bon réflexe (`TICKET_DOMAIN = b"helios-tpm-reseal-v1"`).
On le généralise :

```
octets_signés = DOMAINE_ARTEFACT ‖ version_format ‖ payload_canonique
```

Chaque type d'artefact a son domaine (`helios-tpm-reseal-v2`,
`helios-wg-recovery-v1`, …) : une signature de billet ne peut pas être rejouée
comme signature de fichier de récupération. Le payload est sérialisé de façon
**canonique** (ordre des champs fixe, pas de JSON re-sérialisé à la volée) —
sinon deux encodages du même contenu produisent deux signatures valides
différentes, ce qui ouvre des ambiguïtés.

### 4. Le fichier de récupération a besoin d'anti-rejeu, pas seulement d'une signature

**C'est le point que la signature seule ne règle pas.** Un fichier de
récupération légitimement signé reste valide pour toujours. Un attaquant qui en
conserve un vieil exemplaire peut le rejouer plus tard pour **restaurer une
ancienne identité** — potentiellement une clé qu'il a compromise entre-temps, et
que la rotation avait justement remplacée.

Il faut donc lier le fichier à un contexte non rejouable. Deux liaisons, à
cumuler :

* **compteur monotone** — obligatoire, comme l'anti-rollback du billet : un
  fichier de version ≤ courante est refusé. Voir **l'amendement 2** sur la nature
  exacte de ce compteur, qui reste à trancher ;
* **empreinte PCR** — **optionnelle** (« si présent, doit correspondre »). La
  version initiale de cet ADR la rendait obligatoire : c'était une erreur, voir
  **l'amendement 1**.

Sans cela, on aurait signé un artefact rejouable — une fausse sécurité.

### 5. Où vit le code

* **`aether::sig`** (nouveau) — l'abstraction `SignatureSuite`, l'enveloppe et la
  vérification hybride. Dans `aether` parce que le client Orion en aura besoin
  s'il vérifie un jour des artefacts éditeur.
* **`helio-tpm`** — consomme `aether::sig` pour le billet et la récupération ;
  perd sa dépendance directe à `ed25519-dalek`.
* **Ancrage de confiance** — les clés publiques éditeur (Ed25519 + ML-DSA) sont
  **compilées dans le binaire**. Une rotation de clé éditeur exige donc une mise
  à jour firmware, ce qui est le comportement voulu pour une racine de confiance.

## Choix arrêtés

### Dépendances

| Besoin | Crate | Détail |
|---|---|---|
| ML-DSA-65 | **`fips204` 0.4.x** | signature (outil éditeur) + vérification (gateway) |
| Ed25519 | **`aws-lc-rs`** | `ed25519-dalek` retiré de `helio-tpm` — un seul backend |
| ML-KEM / AEAD / hash | **`aws-lc-rs`** | inchangé vs ADR-001 ; feature `fips` reste **optionnelle** |
| SLH-DSA | **aucun** | prévu par le format *n*-signatures uniquement |

Le raisonnement derrière ce découpage est l'**option A** ci-dessous : sortir les
signatures d'`aws-lc-rs` découple la racine de confiance de la décision FIPS.

Règle de travail : lire la source du crate dans `~/.cargo/registry` avant
d'écrire contre son API. `fips204` n'a pas d'audit public connu et un mainteneur
unique — acceptable ici parce que la gateway ne fait que **vérifier**, jamais
signer, mais la version est à épingler.

### Politique de vérification

```rust
const REQUIRED_ALGS: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];
```

Chaque entrée → une signature présente **et** valide, sinon rejet. Algorithmes
inconnus supplémentaires : ignorés (compatibilité avant). Jamais « au moins une ».

### Placement du code

| Crate | Rôle |
|---|---|
| **`aether::sig`** | `AlgId`, enveloppe, `verify` hybride, `sign` derrière une feature |
| **`helio-tpm`** | consomme `aether::sig` pour le billet et la récupération |
| **outil éditeur** | seul binaire compilant `sign` ; détient les clés privées |
| **gateway** | `verify` **seul** ; clés publiques éditeur compilées dans le binaire |

### Amendement 1 — la liaison PCR du fichier de récupération est *optionnelle*

**Correction d'une erreur de la première rédaction.** La décision 4 exigeait que
le digest PCR courant corresponde. Or **le fichier de récupération n'existe que
parce que les PCR ont changé** : l'éditeur devrait prédire le digest PCR 0/4/7
*post-mise à jour* au moment de signer. C'est faisable par précalcul, mais ça
casse dès qu'une machine du parc a un firmware ou une configuration Secure Boot
légèrement différente — et l'échec est **définitif** : PCR non prédit →
récupération refusée → clé perdue. Exactement le scénario que le séquestre
existe pour éviter.

Donc, en reprenant la forme déjà en place pour le billet
(`reseal_ticket.rs`, `expected_pcr_digest: Option<[u8; 32]>`) :

* **compteur monotone : obligatoire** ;
* **digest PCR : optionnel** — « si présent, doit correspondre ».

### Amendement 2 — nature du compteur monotone, à trancher explicitement

Ce qui existe aujourd'hui n'est **pas** un compteur TPM : c'est
`TpmState { version }` dans le blob store (`provisioning.rs`, `blob_store.rs`),
c'est-à-dire un fichier. Sa résistance au rollback vaut donc l'intégrité de ce
fichier face à un attaquant capable d'écrire sur la partition de configuration —
soit **le même attaquant que celui contre lequel cet ADR défend**.

Deux réponses admissibles, à choisir au lot 3 et à documenter :

1. réutiliser `TpmState.version`, en écrivant l'hypothèse de confiance associée ;
2. utiliser un vrai compteur monotone en NV du TPM.

Ne pas laisser l'implémentation trancher implicitement.

### Amendement 3 — `key_epoch` doit être dans les octets signés

La première rédaction plaçait `key_epoch` dans l'enveloppe mais **hors** des
octets signés : un attaquant le réécrit librement, et s'il sélectionne la clé de
vérification, c'est un sélecteur non authentifié. Forme correcte :

```
octets_signés = DOMAINE_ARTEFACT ‖ version_format ‖ key_epoch ‖ payload_canonique
```

`key_epoch` indexe un trousseau compilé (`const PUBLISHER_KEYS: &[(u32, …)]`) ;
une époque inconnue est un rejet. Si on ne veut pas de trousseau, il faut retirer
le champ plutôt que le laisser décoratif.

### Amendement 4 — la bascule Ed25519 doit être prouvée par les tests

`reseal_ticket.rs` vérifiait via `verify_strict()` de `ed25519-dalek`, qui rejette
les points d'ordre faible et les encodages non canoniques. La migration doit
porter ces tests sur le nouveau chemin, pas supposer l'équivalence.

**Résultat du portage (2026-07-19)** : `aws-lc-rs` 1.17.1 rejette bien un scalaire
`S` non canonique, mais accepte la forge triviale où la clé publique et `R` sont
le point identité. `aether::sig` conserve donc AWS-LC comme backend de signature
et effectue avant lui les contrôles stricts de décompression, de petit ordre et
de scalar canonique via `curve25519-dalek` (déjà présent pour X25519). Le vecteur
est gardé comme test de non-régression.

### Domaines de séparation

Le domaine actuel est `helios-tpm-reseal-v1` : conserver le préfixe complet.

* billet de rescellement → `helios-tpm-reseal-v2`
* fichier de récupération → `helios-wg-recovery-v1`

### Hors périmètre

* Pas de confidentialité du fichier de récupération (clé en clair au démarrage).
* Pas de certification FIPS 140-3 CMVP comme critère d'acceptation.
* Pas de ML-DSA via `aws-lc-rs` `unstable`.

## Arbitrage : pourquoi ces choix (conservé pour mémoire)

### ⚠️ Conflit direct avec le plan FIPS

`aws-lc-rs` 1.17 **sait** faire ML-DSA — mais :

```rust
#![cfg(feature = "unstable")]        // « not covered by semver guarantees »
#[cfg(not(feature = "fips"))]        // ← indisponible AVEC la feature fips
pub mod signature;
```

Deux contraintes cumulées :

1. l'API est **`unstable`**, sans garantie de compatibilité entre versions ;
2. elle est **exclue quand `fips` est activée** — or activer `fips` plus tard est
   une décision déjà prise (ADR-001 §2).

Prendre ML-DSA depuis `aws-lc-rs` reviendrait donc à **fermer la porte FIPS**,
ou à devoir tout redéfaire le jour où on l'ouvre. SLH-DSA, lui, est simplement
absent d'`aws-lc-rs`.

**Trois options :**

| | Approche | Conséquence |
|---|---|---|
| **A** *(recommandé)* | Signatures depuis un crate **pur-Rust** dédié (`fips204` 0.4.6, ou `ml-dsa` RustCrypto), `aws-lc-rs` conservé pour ML-KEM et l'AEAD | Découple la racine de confiance de la décision FIPS. Vérification seule côté gateway : surface d'attaque réduite. Coût : une dépendance crypto de plus |
| **B** | `aws-lc-rs` + `unstable` | Aucune dépendance nouvelle, mais **renonce à FIPS** et s'expose aux ruptures d'API |
| **C** | Attendre la stabilisation de ML-DSA sous `fips` dans `aws-lc-rs` | Le fichier de récupération reste **non signé** entre-temps — inacceptable |

Je recommande **A** : la signature est une opération de *vérification* sur la
gateway (jamais de signature), donc le risque d'implémentation y est faible, et
ça préserve les deux futurs.

### Choix de l'algorithme PQ : ML-DSA-65 ou SLH-DSA ?

| | Signature | Clé publique | Hypothèse de sécurité |
|---|---|---|---|
| **ML-DSA-65** (FIPS 204) | ~3,3 ko | 1 952 o | Réseaux euclidiens (structurés) |
| **SLH-DSA-128s** (FIPS 205) | ~7,9 ko | 32 o | **Fonctions de hachage seules** |

SLH-DSA est le choix *conservateur* pour une racine de confiance : sa sécurité ne
repose que sur des fonctions de hachage, aucune structure algébrique à casser.
C'est l'argument qui compte pour un artefact vérifié pendant quinze ans.

Mais il est absent d'`aws-lc-rs`, et le crate pur-Rust est en `0.2.0-rc`.

**Proposition** : partir sur **ML-DSA-65** maintenant, avec un format d'enveloppe
qui accepte **n** signatures — de sorte qu'ajouter SLH-DSA plus tard soit une
extension de la liste exigée, pas une refonte. Si la conservation à très long
terme prime sur la taille, on peut aussi étager : SLH-DSA pour l'ancrage et les
rotations de clés (rares, taille indifférente), ML-DSA pour les artefacts
courants.

## Migration

Rien n'est déployé : **rupture nette**, pas de période de tolérance. Les billets
Ed25519 seuls (`helios-tpm-reseal-v1`) sont refusés ; le nouveau format est `v2`.
Une période de double acceptation serait précisément une fenêtre de downgrade.

## Ce que cela ne protège pas

À énoncer pour ne pas se raconter d'histoires :

* **La confidentialité du fichier de récupération.** La clé y reste en clair le
  temps d'un démarrage (ADR-001 / `gateway_key`). Signer empêche l'**injection**,
  pas la **lecture**. Le fichier reste un secret à manipuler comme tel.
* **Un attaquant qui obtient la clé privée de l'éditeur.** Aucune signature n'y
  résiste ; c'est le problème du stockage hors ligne / HSM de cette clé.
* **Le rejeu**, sans les liaisons de la décision 4 — la signature seule ne suffit
  pas.

## Estimation

| Lot | Contenu | Prérequis |
|---|---|---|
| 1 | `aether::sig` : enveloppe (`key_epoch` **signé**, amendement 3), suite hybride, trousseau compilé, vérification anti-downgrade + tests dédiés | — |
| 2 | Billet de rescellement → enveloppe `v2` ; `ed25519-dalek` retiré de `helio-tpm` ; **tests existants portés** (amendement 4) | lot 1 |
| 3 | Fichier de récupération signé : compteur obligatoire + PCR optionnel (amendement 1), câblage `gateway_key` | lot 1 + **trancher l'amendement 2** |
| 4 | Outil éditeur de signature (hors gateway) et documentation opérateur | lot 1 |

Les lots 1 à 3 sont entièrement testables sur WSL2 : c'est de la crypto pure,
sans plan de données.

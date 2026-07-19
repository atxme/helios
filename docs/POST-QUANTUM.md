# Cryptographie post-quantique

Helios utilise deux mécanismes post-quantiques distincts. Ils ne répondent pas
au même risque et ne doivent pas être confondus.

| Usage | Algorithme | Composition | État |
|---|---|---|---|
| Secret de session WireGuard | ML-KEM-768 | tunnel WireGuard classique puis PSK PQ | protocole implémenté, installation atomique du PSK gateway à terminer |
| Artefacts éditeur | ML-DSA-65 + Ed25519 | hybride AND obligatoire | billet TPM v2 implémenté ; récupération bloquée |

## PSK WireGuard dérivé par ML-KEM

WireGuard n’est pas modifié. L’admission initiale utilise ses clés Curve25519
classiques. Une fois ce tunnel établi, Orion et Helios exécutent ML-KEM-768 sur
le canal HTTP interne :

1. Orion génère une paire ML-KEM éphémère et envoie la clé publique, son
   identité WireGuard et un nonce ;
2. Helios vérifie que le pair est déjà admis, encapsule un secret et renvoie le
   ciphertext, son identité et un second nonce ;
3. les deux côtés dérivent le même PSK de 32 octets en liant secret KEM,
   identités, nonces et domaine de protocole ;
4. le PSK doit ensuite être installé atomiquement dans le slot
   `PresharedKey` du pair WireGuard.

Le code utilise ML-KEM-768 d’`aws-lc-rs`. Les tests couvrent le round-trip, les
clés/ciphertexts malformés, les mauvaises clés, les nonces, les identités et la
séparation des concaténations. Le dernier câblage du plan de données reste hors
du niveau de garantie production.

## Signatures hybrides d’artefacts

Un artefact critique est accepté seulement si **les deux** signatures requises
sont présentes et valides :

```rust
const REQUIRED_ALGS: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];
```

La politique est compilée, pas choisie par l’artefact. Les algorithmes inconnus
supplémentaires sont ignorés pour permettre une extension future, mais un
algorithme requis absent, dupliqué, mal encodé ou invalide entraîne un rejet.

Les octets signés sont :

```text
DOMAINE || version_format || key_epoch || payload_canonique
```

`key_epoch` indexe `PUBLISHER_KEYS`, un trousseau public compilé. Une époque
inconnue est rejetée. Les structures JSON refusent les champs inconnus ; la
sérialisation signée ne dépend pas de l’ordre JSON.

Le billet de rescellement utilise le domaine `helios-tpm-reseal-v2`. Il porte un
compteur obligatoire et un digest PCR optionnel. Le format
`helios-tpm-reseal-v1` Ed25519 seul n’est jamais accepté.

## Backends et contrôles Ed25519 stricts

- ML-DSA-65 : `fips204` 0.4.6 épinglé ; signature seulement dans l’outil
  éditeur, vérification dans la gateway ;
- Ed25519 : `aws-lc-rs` ;
- contrôles stricts : décompression, rejet des points de petit ordre et scalaire
  `S` canonique via `curve25519-dalek` avant AWS-LC.

Ces précontrôles sont nécessaires : le test adversarial du point identité a
montré qu’AWS-LC 1.17.1 seul n’offrait pas l’équivalent de
`ed25519-dalek::verify_strict()` pour ce vecteur.

## Gestion des clés éditeur

Les clés privées n’existent que sur le poste éditeur utilisant
`helios-publisher`. Le firmware contient les clés publiques. Un build release
sans `HELIOS_PUBLISHER_KEYRING_PATH` échoue ; le trousseau de développement est
réservé aux builds debug et n’apporte aucune sécurité.

Le guide opératoire est [PUBLISHER-SIGNING.md](PUBLISHER-SIGNING.md). Les choix,
limites et motifs sont conservés dans
[ADR-002-SIGNATURES-PQ.md](ADR-002-SIGNATURES-PQ.md).

## Limites explicites

- le PSK PQ n’est pas encore installé de bout en bout dans la gateway réelle ;
- le fichier de récupération signé attend le choix du compteur anti-rejeu ;
- ML-DSA ne signifie pas que le binaire est certifié FIPS 140-3 ;
- SLH-DSA est extensible par le format mais n’est pas actuellement requis.

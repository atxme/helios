# Cryptographie post-quantique

Helios utilise deux mécanismes post-quantiques distincts. Ils ne répondent pas
au même risque et ne doivent pas être confondus.

| Usage | Algorithme | Composition | État |
|---|---|---|---|
| Secret de session WireGuard | ML-KEM-1024 + HKDF-SHA-512 | transcript ML-DSA-65 sur QUIC/TLS puis PSK WireGuard | de bout en bout ; scellement DPAPI non exerçable en WSL2 |
| Identité de key-negotiation | ML-DSA-65 | certificat PQ applicatif et signatures requête/réponse/commit | implémenté |
| Artefacts éditeur | ML-DSA-65 + Ed25519 | hybride AND obligatoire | billet TPM v2 implémenté ; récupération bloquée |

## PSK WireGuard dérivé par ML-KEM

WireGuard n’est pas modifié. Avant son premier handshake, Orion et Helios
exécutent la key-negotiation sur un port QUIC/mTLS distinct :

1. mTLS établit le transport QUIC, sans être l'unique ancre de sécurité ;
2. les certificats applicatifs ML-DSA-65 lient les identités aux clés
   WireGuard ;
3. Orion choisit `classic`, `static_psk` ou `ml_kem` et signe le mode ainsi que
   `kpub` ;
4. en ML-KEM, Orion génère `kpub`/`kpriv`, Helios encapsule et signe le
   ciphertext ;
5. HKDF lie secret KEM, transaction, mode, nonces et identités WireGuard ;
6. Helios pose son slot avant de répondre, Orion pose le sien puis attend un
   handshake frais ;
7. confirmation et ACK ML-DSA-65 commit la transaction ; toute fermeture ou
   expiration restaure le slot précédent.

Le plancher persistant `minimum_key_negotiation_mode` est vérifié séparément par
Helios et Orion. Pour un pair PQ, `classic` et `static_psk` sont refusés avant
toute pose. Chaque commit réussi élève le plancher Helios au mode utilisé et le
persiste sans PSK ni clé privée ; le protocole ne sait jamais le diminuer. Les
messages v1 sans signatures PQ sont incompatibles et rejetés.

Le code utilise ML-KEM-1024 d’`aws-lc-rs`. Les tests couvrent le round-trip, les
clés/ciphertexts malformés, les mauvaises clés, les nonces, les identités, le
refus de downgrade, substitution de `kpub`/ciphertext, signatures de commit,
mTLS et rollback. Les PSK négociés restent
uniquement en mémoire et dans les slots WireGuard.

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
[ADR-002-SIGNATURES-PQ.md](../adr/ADR-002-SIGNATURES-PQ.md).

## Limites explicites

- le fournisseur de clé de certificat dans le shell Windows et son IHM seront
  câblés dans le lot IHM ; le cœur impose déjà cette frontière protégée ;
- l'effet réel sur WireGuard-NT, le noyau Linux, les redirections des deux ports
  et le scellement TPM restent à valider sur les cibles matérielles ;
- le fichier de récupération signé attend le choix du compteur anti-rejeu ;
- ML-DSA ne signifie pas que le binaire est certifié FIPS 140-3 ;
- SLH-DSA est extensible par le format mais n’est pas actuellement requis.

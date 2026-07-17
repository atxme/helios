# Échange de clés post-quantique (hybride)

Helios impose un échange de clés **hybride** : un algorithme classique (ECDHE) et
un algorithme post-quantique (ML-KEM) sont combinés. La clé de session n'est
cassée que si **les deux** le sont — on conserve la sécurité éprouvée d'ECDHE
tout en se protégeant contre un futur ordinateur quantique (modèle « *harvest
now, decrypt later* »).

## Mécanisme : IKEv2 multiple key exchanges (RFC 9370)

IKEv2 permet plusieurs échanges de clés successifs dans une même négociation.
On en utilise deux :

- **échange principal** : `ecp384` — ECDHE sur P-384 ;
- **échange additionnel 1** : `ke1_mlkem768` — ML-KEM-768 (Kyber, FIPS 203).

Dans une proposition strongSwan, cela donne :

```
aes256gcm16-prfsha384-ecp384-ke1_mlkem768
│         │         │      └─ KE additionnel : ML-KEM-768 (post-quantique)
│         │         └──────── KE principal : ECDHE P-384 (classique)
│         └────────────────── PRF : HMAC-SHA-384
└──────────────────────────── chiffrement IKE : AES-256-GCM
```

C'est la valeur du champ `ike_proposal` dans `helios.toml`.

## Prérequis sur la cible

- **strongSwan ≥ 6.0** avec le support des échanges de clés additionnels et un
  plugin fournissant ML-KEM (selon la build : `ml`, ou `oqs` via liboqs).
- Vérifier les KE disponibles : `swanctl --list-algs | grep -i kem`.

## Où c'est appliqué dans le code

- `aether::config::Connection::ike_proposal` porte la proposition ;
- `heliosd` la transmet à charon via `load-conn` (voir `orchestrator::load_connection`).

Le plan de données (ESP) reste symétrique (AES-256-GCM) : seul l'**établissement
des clés** est post-quantique, ce qui suffit à la confidentialité long terme.

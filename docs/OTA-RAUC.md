# Mises à jour OTA — image A/B (RAUC)

Helios met à jour l'appliance par **images A/B** avec **rollback automatique**,
via [RAUC](https://rauc.io). C'est le standard pour l'embarqué robuste.

## Principe

Deux slots rootfs (A et B). À tout instant l'un est actif, l'autre inactif.

```
[slot A actif] ──install──▶ [slot B reçoit la nouvelle image]
        │                              │
        │                          reboot vers B
        ▼                              ▼
   reste sur A               health check sur B
   si échec install        ┌── ok  : mark-good → B confirmé
                           └── KO  : bootloader → ROLLBACK vers A
```

L'atomicité et le partitionnement sont gérés par **RAUC + le bootloader**.
Helios se contente de piloter `rauc` et de **confirmer le boot**.

## Rôle de heliosd

`helios-update::RaucChannel` enveloppe le binaire `rauc` :

| Méthode              | Commande RAUC                | Quand                              |
|----------------------|------------------------------|-----------------------------------|
| `check`              | (lecture de l'index)         | périodiquement (`check_interval_secs`) |
| `install(release)`   | `rauc install <bundle>`      | si une version plus récente existe |
| `confirm_boot`       | `rauc status mark-good`      | **au démarrage**, après un boot sain |

Le `mark-good` au démarrage est essentiel : sans lui, le bootloader considère le
boot comme non confirmé et **rollback** au prochain redémarrage. C'est ce qui
rend une mise à jour ratée non-fatale.

## Sécurité des bundles

Les bundles `.raucb` sont **signés** ; RAUC vérifie la signature contre le
keyring (`/etc/rauc/keyring.pem`) avant d'écrire le slot. Voir
[`deploy/rauc/system.conf`](../deploy/rauc/system.conf).

RAUC protège l’image elle-même. L’autorisation de **resceller** les secrets TPM
après le changement de PCR est une opération distincte : elle exige un billet
`helios-tpm-reseal-v2` signé à la fois par Ed25519 et ML-DSA-65. Le compteur doit
strictement augmenter ; le digest PCR est facultatif et, s’il est fourni, doit
correspondre. Voir [PUBLISHER-SIGNING.md](PUBLISHER-SIGNING.md).

## Statut

`RaucChannel` pilote `rauc install` / `mark-good`. À finaliser sur la cible :
le parsing de `rauc status --output-format=json` pour lire le slot actif, et le
remplacement de l'index local par une source HTTPS signée.

La recette de livraison doit tester le chemin sain (`mark-good`) et un boot
volontairement défaillant qui revient au slot précédent. Le fichier de
récupération WireGuard signé n’est pas encore disponible : son compteur
anti-rejeu reste à arbitrer dans l’ADR-002.

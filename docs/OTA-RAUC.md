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

## Statut

`RaucChannel` pilote `rauc install` / `mark-good`. À finaliser sur la cible :
le parsing de `rauc status --output-format=json` pour lire le slot actif, et le
remplacement de l'index local par une source HTTPS signée.

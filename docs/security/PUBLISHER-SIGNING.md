# Signature des artefacts éditeur

`helios-publisher` est l'unique binaire du workspace qui active l'API de
signature de `aether`. Il doit être construit et exécuté sur le poste éditeur,
jamais sur une gateway.

## Créer une époque de clés

```sh
cargo run -p helios-publisher -- keygen \
  --key-epoch 1 \
  --output-dir /chemin/hors-ligne/helios-publisher-epoch-1
```

La commande refuse un répertoire déjà présent. Elle produit deux secrets :

- `ed25519-private.pk8` ;
- `ml-dsa-65-private.bin`.

Ils doivent rester hors ligne ou dans un HSM adapté. Le troisième fichier,
`publisher-keyring.json`, ne contient que les clés publiques. Pour une rotation,
ajouter la nouvelle entrée au tableau sans supprimer l'époque encore nécessaire
aux artefacts en circulation, puis livrer ce nouveau trousseau dans un firmware.
Les `key_epoch` doivent être uniques.

Le build de production reçoit le chemin du trousseau public :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd
```

Une release sans cette variable échoue au build. Le trousseau debug porte aussi
un marqueur `development: true` : il est refusé en release même si son chemin
est fourni explicitement. Ses clés privées sont publiques et il ne fournit
aucune sécurité.

## Signer un billet de rescellement v2

```sh
cargo run -p helios-publisher -- reseal-ticket \
  --key-epoch 1 \
  --version 42 \
  --ed25519-private-key /chemin/hors-ligne/helios-publisher-epoch-1/ed25519-private.pk8 \
  --ml-dsa-65-private-key /chemin/hors-ligne/helios-publisher-epoch-1/ml-dsa-65-private.bin \
  --keyring /chemin/public/publisher-keyring.json \
  --output reseal-ticket.json
```

`--version` doit être strictement supérieur à la version déjà consommée par la
gateway. `--expected-pcr-digest <64 caractères hex>` est facultatif ; s'il est
présent, la gateway exige une correspondance exacte. L'outil refuse d'écraser
un fichier existant, vérifie que les secrets correspondent à l'époque du
trousseau, produit les deux signatures et auto-vérifie l'enveloppe avant
l'écriture.

Les deux signatures couvrent exactement :

```text
"helios-tpm-reseal-v2" || u32_be(2) || u32_be(key_epoch)
  || u64_be(version) || présence_pcr || digest_pcr_si_présent
```

Il n'existe aucun mode Ed25519 seul et aucun fallback vers
`helios-tpm-reseal-v1`.

## Fichier de récupération WireGuard

Sa signature reste volontairement non implémentée. Le lot est bloqué jusqu'au
choix explicite entre `TpmState.version` sur fichier et un vrai compteur
monotone NV du TPM. La PCR y sera optionnelle ; le compteur, obligatoire.

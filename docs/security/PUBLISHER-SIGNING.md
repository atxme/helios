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

## Signer un billet de rescellement v3

```sh
cargo run -p helios-publisher -- reseal-ticket \
  --request reseal-request.json \
  --key-epoch 1 \
  --ed25519-private-key /chemin/hors-ligne/helios-publisher-epoch-1/ed25519-private.pk8 \
  --ml-dsa-65-private-key /chemin/hors-ligne/helios-publisher-epoch-1/ml-dsa-65-private.bin \
  --keyring /chemin/public/publisher-keyring.json \
  --output reseal-ticket.json
```

`reseal-request.json` est le `ResealRequest` produit par `heliosd tpm
prepare-reseal` sur la gateway : le compteur courant et l'ancre du blob scellé.
L'outil signe ces deux valeurs telles quelles et refuse tout champ inconnu.
`--expected-pcr-digest <64 caractères hex>` est facultatif ; s'il est présent,
la gateway exige une correspondance exacte. L'outil refuse d'écraser
un fichier existant, vérifie que les secrets correspondent à l'époque du
trousseau, produit les deux signatures et auto-vérifie l'enveloppe avant
l'écriture.

Les deux signatures couvrent exactement :

```text
"helios-tpm-reseal-v3" || u32_be(3) || u32_be(key_epoch)
  || u64_be(counter) || ancre_blob (32 octets) || présence_pcr
  || digest_pcr_si_présent
```

Il n'existe aucun mode Ed25519 seul et aucun fallback vers
`helios-tpm-reseal-v1`.

## Signer une récupération WireGuard

```sh
cargo run -p helios-publisher -- wg-recovery \
  --request wg-recovery-request.json \
  --key-epoch 1 \
  --ed25519-private-key /chemin/hors-ligne/helios-publisher-epoch-1/ed25519-private.pk8 \
  --ml-dsa-65-private-key /chemin/hors-ligne/helios-publisher-epoch-1/ml-dsa-65-private.bin \
  --keyring /chemin/public/publisher-keyring.json \
  --output wg-recovery-authorization.json
```

`wg-recovery-request.json` est la requête écrite par `helios escrow
prepare-recovery` sur le poste opérateur, à partir du séquestre `wg-key.escrow`
(un `WireGuardRecoveryPayload` : `counter`, `gateway_public_key` et
`expected_pcr_digest` facultatif). L'éditeur ne voit jamais la clé privée
WireGuard : la requête est publique. L'outil signe ce JSON tel quel, refuse tout
champ inconnu et n'écrase jamais un fichier existant.

Le `counter` signé doit être celui que la gateway attend au moment de la
récupération. Si un billet de rescellement est consommé dans le même démarrage,
la récupération vise la valeur suivante : billet pour `C`, récupération pour
`C+1`. `prepare-recovery` propose `C+1` par défaut, d'après le séquestre ;
l'opérateur vérifie la valeur sur la gateway (`heliosd tpm counter-status`) avant
de signer. Sans billet dans le même démarrage (coffre perdu simplement), la
valeur à passer avec `--counter` est le compteur courant `C`, et non `C+1` ; dans
Orion, la même valeur va dans le champ facultatif « Valeur du compteur (lue sur la
gateway) ».

Les deux signatures couvrent exactement :

```text
"helios-wg-recovery-v1" || u32_be(1) || u32_be(key_epoch)
  || u64_be(counter) || clé_publique_gateway (32 octets) || présence_pcr
  || digest_pcr_si_présent
```

La gateway n'accepte cette autorisation que si son `counter` égale la valeur
courante du compteur NV, et si la clé privée du fichier dérive
`gateway_public_key`. Le fichier de récupération est déposé par l'opérateur
hors bande (voir [MAINTENANCE.md](../MAINTENANCE.md)).

## Signer une release applicative

Construire le frontend puis le binaire une seule fois. Le SHA-256 de ce fichier
est l’identité de promotion entre test et production : il est interdit de le
recompiler après la campagne de laboratoire.

```sh
npm run build --prefix web
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui

cargo run -p helios-publisher -- binary-release \
  --key-epoch 1 \
  --release-sequence 42 \
  --channel production \
  --version 1.2.0 \
  --git-commit "$(git rev-parse --short=16 HEAD)" \
  --target x86_64-unknown-linux-gnu \
  --features embed-ui,netlink,tpm,wireguard \
  --binary target/release/heliosd \
  --ed25519-private-key /chemin/hors-ligne/epoch-1/ed25519-private.pk8 \
  --ml-dsa-65-private-key /chemin/hors-ligne/epoch-1/ml-dsa-65-private.bin \
  --keyring /chemin/public/publisher-keyring.json \
  --output heliosd.release.json
```

Pour la gateway de laboratoire, signer d’abord avec `--channel testing` et
l’époque éditeur déjà compilée dans le binaire. Après la campagne, rejouer la
commande avec `--channel production`, la même époque et le **même** fichier
`target/release/heliosd`. Comparer le SHA-256 affiché par les deux commandes
avant publication. Le canal appartient au payload signé : une gateway de
production refuse le manifeste `testing` sans exiger un binaire différent.

Les campagnes automatisées génèrent un trousseau éphémère pour tester le
mécanisme sans exposer les clés éditeur. Le binaire ainsi produit est un
artefact de campagne et ne peut pas être promu en production.

Le compteur `release_sequence` doit être strictement supérieur à celui déjà
confirmé sur les gateways. L’outil valide également l’en-tête ELF et sa target,
trie les features, refuse l’écrasement du manifeste et auto-vérifie les deux
signatures.

### Déploiement applicatif courant depuis le poste de développement

Quand le même poste tient les rôles de build, d’éditeur et d’opérateur, le
flux principal est une seule commande :

```sh
./scripts/deploy-app.sh
```

Elle construit le frontend et le seul binaire `heliosd`, signe le manifeste,
transfère l’artefact par l’API derrière `helios0`, demande son activation puis
attend que la gateway confirme la nouvelle séquence. La compilation incrémentale
peut réutiliser un frontend déjà construit avec `--skip-frontend`. Pour une
gateway de laboratoire ou une URL non standard :

```sh
./scripts/deploy-app.sh --channel testing --url http://100.64.0.1:8080
```

Le transfert seul reste utilisable avec des artefacts préparés ailleurs :

```sh
helios --url http://100.64.0.1:8080 app-update \
  --manifest heliosd.release.json --binary heliosd
```

Depuis PowerShell sous Windows, le script natif pilote la même commande et
envoie un ELF Linux déjà construit et son manifeste signé :

```powershell
.\scripts\deploy-app.ps1 `
  -Manifest .\heliosd.release.json `
  -Binary .\heliosd `
  -Yes
```

`-HeliosCtl C:\outils\helios.exe` évite `cargo run` lorsqu'un binaire
Windows de l'outil est déjà disponible. Windows ne construit pas nativement
le daemon Linux et ses dépendances noyau/TPM. Quand le dépôt et les clés
éditeur vivent dans WSL, PowerShell peut lancer la chaîne complète :

```powershell
.\scripts\deploy-app.ps1 `
  -BuildInWsl `
  -WslRepo /home/utilisateur/helios
```

Dans ce second mode, build, signature et transfert s'exécutent dans WSL ;
`-WslDistribution Ubuntu` sélectionne explicitement la distribution. Si WSL
ne voit pas la route installée par Orion sous Windows, produire les artefacts
dans WSL puis employer le premier mode fait partir l'appel API de Windows.

Sans `--yes`, `helios` demande confirmation après le staging. `--stage-only`
n’active rien. Ce chemin ne remplace pas le bundle signé : une modification de
`helios-installer`, `helios` ou d’une unité systemd exige toujours un bundle.

## Signer un bundle d’installation

Un bundle porte le daemon, l’installateur, l’outil d’exploitation, les unités
systemd et un exemple de configuration. Sa signature est **distincte** de celle
d’une release binaire, et son domaine l’est aussi (`helios-bundle-v1`) : une
signature de bundle ne peut pas être rejouée comme signature de release, ni
l’inverse.

Assembler d’abord, sur le poste de build :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo xtask bundle
```

Puis signer, sur le poste éditeur :

```sh
cargo run -p helios-publisher -- bundle \
  --dir target/bundle/helios-0.1.0-x86_64-unknown-linux-gnu \
  --key-epoch 1 \
  --release-sequence 42 \
  --channel production \
  --version 0.1.0 \
  --git-commit "$(git rev-parse --short=16 HEAD)" \
  --target x86_64-unknown-linux-gnu \
  --ed25519-private-key /chemin/hors-ligne/epoch-1/ed25519-private.pk8 \
  --ml-dsa-65-private-key /chemin/hors-ligne/epoch-1/ml-dsa-65-private.bin \
  --keyring /chemin/public/publisher-keyring.json
```

La commande écrit `manifest.json` dans le répertoire. Le manifeste énumère
**exhaustivement** le contenu, avec pour chaque fichier sa taille, son empreinte
SHA-256 et son bit d’exécution. L’installateur refuse un fichier modifié, un
fichier manquant **et** un fichier surnuméraire : glisser une unité systemd non
signée à côté de celles qui le sont ne passe pas.

`--release-sequence` partage le compteur d’anti-rollback des releases binaires
(ADR-003 §4) : une même release porte la même séquence dans son bundle et dans
son manifeste `heliosd`. Installer un bundle sème ce compteur, ce qui interdit
d’y appliquer ensuite une mise à jour applicative plus ancienne.

Archiver enfin — `pack` refuse un répertoire sans manifeste, de sorte qu’un
bundle non signé ne puisse pas partir par distraction :

```sh
cargo xtask pack --dir target/bundle/helios-0.1.0-x86_64-unknown-linux-gnu
```

L’empreinte affichée est celle à publier avec l’archive : c’est elle que
l’opérateur compare avant le tout premier `helios-installer bootstrap`, quand
aucun installateur vérifié n’existe encore sur la machine.

## Fichier de récupération WireGuard

La signature de ce fichier est décrite plus haut, dans « Signer une récupération
WireGuard ». Sa PCR est optionnelle ; son compteur est obligatoire et vient du
compteur NV du TPM.

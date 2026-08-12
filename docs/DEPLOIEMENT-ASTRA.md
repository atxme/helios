# Déployer Astra et amorcer un domaine de confiance

Guide opératoire de l'[ADR-008](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md). Il
décrit ce qui existe aujourd'hui et **nomme ce qui manque encore**, parce qu'un
guide qui laisse croire que la rotation fonctionne coûte une journée à celui
qui le suit.

## Deux commandes

```sh
astra-signer init --rp-id astra.helios.local --label "YubiKey du bureau"
./scripts/deploy.sh
```

C'est tout. La première exige une clé de sécurité branchée et ne peut pas être
automatisée — c'est le but d'une clé physique. La seconde fait le reste :
image, transfert, amorçage d'Astra, amorçage du registre gateway, redémarrage.

Aucune valeur n'est recopiée à la main. `init` écrit un **relais** public à côté
du coffre (`~/.helios/astra/astra-domain.json`) : domaine, RP ID, ancre `CA-PQ`.
`deploy.sh` le lit, demande à la gateway son identité servie
(`heliosd show-identity`), amorce Astra, **capture** dans sa sortie la clé de
service et la tête de chaîne d'audit, les reporte dans le `.env` distant et
enchaîne sur `heliosd init-trust-domain`.

Sans relais, `deploy.sh` saute cette partie en une ligne et déploie la gateway
comme avant : une gateway sans autorité reste une gateway qui marche.
`--sans-astra` la saute explicitement.

## Ce que ce lot livre, et ce qu'il ne livre pas

Après ce guide, vous avez : un domaine de confiance existant des deux côtés, un
coffre d'autorité ouvert par clé de sécurité, un Astra qui tourne et tient son
registre et sa chaîne d'audit, une gateway dont les routes de cycle de vie
in-tunnel sont ouvertes.

Vous n'avez **pas** de rotation automatique de certificats. Il manque :

- les **commandes de signature** d'`astra-signer` — certificat auto-signé
  `CA-TLS`, `AstraIssuerAuthorization`, campagnes. Sans la deuxième, Astra n'a
  pas d'émetteur délégué et refuse tout renouvellement ordinaire ; il le
  journalise au démarrage. Les trois routes qui exigent une approbation
  opérateur répondent `501` ;
- le **veth privé Astra–Helios** du §2 : `heliosd` n'a aucun client HTTP vers
  Astra. Les deux services connaissent le même domaine, mais ne se parlent pas
  encore ;
- le **pilote client** du §7 dans `orion-core`, et les routes de rotation
  client d'Astra.

Ce qui est donc réellement éprouvé ici : l'image, le réseau, les volumes, la
sauvegarde, le durcissement, et la cohérence des deux moitiés du domaine.

## Le choix qu'on ne refait pas

Le **RP ID WebAuthn**, avant tout le reste.

Un credential FIDO2 est créé *sous* un RP ID, et une assertion doit présenter
le même. Le coffre le mémorise à `astra-signer init` ; en changer rend tous les
key-slots inouvrables, définitivement, sans recours — la spécification refuse
explicitement toute phrase de passe de secours.

Choisissez un nom que vous garderez : `astra.helios.local` en interne, ou un nom
public si Astra sort. Il se propage ensuite tout seul aux trois endroits qui en
ont besoin.

## Prérequis

- La gateway tourne, et `heliosd init-key-negotiation` a déjà été passé. Le
  registre décrit les leaves effectivement servies ; sans elles il n'y a rien à
  décrire, et `deploy.sh` le dit.
- Un moteur de conteneur sur la gateway (`docker compose` ou `podman compose`).
  Absent, l'étape est sautée avec la commande d'installation en clair.
- **Deux** clés de sécurité FIDO2 avec PIN. Une seule suffit pour commencer :
  l'autorité restera « non amorcée » et le dira à chaque commande, jusqu'à
  l'enrôlement de la seconde.
- Le compagnon bâti sur la machine où la clé se branche :
  `cargo build -p astra-signer`. En **debug** : le garde-fou ADR-002 refuse le
  trousseau éditeur de développement dans toute compilation `--release`, et
  rien ici n'y gagne — le déverrouillage d'un key-slot est un HKDF-SHA256.
  Pour un binaire release, fournir `HELIOS_PUBLISHER_KEYRING_PATH`.
- Sous Windows, **aucune élévation n'est nécessaire** : le compagnon passe par
  l'API WebAuthn du système (`--transport platform`, le défaut), qui demande
  elle-même le PIN et le contact — le PIN n'entre donc jamais dans ce
  processus. Elle exige `WEBAUTHN_API_VERSION_4` pour les sels `hmac-secret` ;
  sur un Windows antérieur, le compagnon le dit et renvoie vers
  `--transport hid`, qui parle CTAP2 directement mais **exige une console
  administrateur** — Windows y réserve l'ouverture d'un HID FIDO aux processus
  élevés depuis la 1903. `astra-signer devices` liste ce que la pile HID
  montre, et distingue « aucun HID » de « des HID, mais aucun FIDO ».
  Un credential est celui de la clé, pas celui de l'API : un coffre créé par un
  transport s'ouvre par l'autre, tant que le RP ID est le même.

## Le détail, si quelque chose casse

### `astra-signer init`

Génère `CA-PQ` (ML-DSA-87) et `CA-TLS`, les scelle sous un key-slot ouvert par
la clé branchée, écrit le coffre et le relais.

Le coffre est à `~/.helios/astra/authority-vault.json` (`%APPDATA%` sous
Windows). **Sauvegardez-le.** Le perdre entièrement, c'est perdre le domaine ;
il est déjà chiffré, donc une copie hors ligne ne coûte rien.

Le relais, à côté, ne contient que du public. `astra-signer domain` le réécrit
depuis le coffre, sans clé de sécurité.

Quand la seconde clé est en main :

```sh
astra-signer enrol --label "YubiKey de récupération"
astra-signer verify        # à faire avec chacune des deux, séparément
```

`enrol` demande d'abord la clé déjà enregistrée, puis la nouvelle : deux objets,
branchés un à la fois. Une troisième ou une quatrième plus tard, c'est la même
commande — rien ne distingue la seconde de la cinquième.

L'ADR ne tient le bootstrap pour fini qu'« après enregistrement **et essai** des
deux clés ». `verify` est cet essai : il ouvre les ancres, pas seulement le
slot.

### Ce que `deploy.sh` fait à l'étape 7

1. détecte `docker compose` ou `podman compose` sur la gateway ;
2. lit le relais — domaine, RP ID, ancre ;
3. `heliosd show-identity` : nom de serveur et clé WireGuard, lus dans la leaf
   PQ servie plutôt que retapés ;
4. construit l'image, la transfère (`docker save | ssh docker load`) ;
5. si le domaine n'est pas amorcé : `astra bootstrap`, capture de la clé de
   service et de la tête d'audit, écriture du `.env` distant, puis
   `heliosd init-trust-domain` et `systemctl restart heliosd` ;
6. `compose up -d`.

L'URL d'autorité vaut `https://<rp_id>` par défaut ; `ASTRA_AUTHORITY_URL` la
remplace.

### À la main

Chaque commande imprime la suivante. `astra bootstrap` imprime la ligne
`heliosd init-trust-domain` complète, et `heliosd init-trust-domain` dit ce qui
manque encore.

## Sauvegardes

Trois objets, trois endroits, et aucun ne remplace un autre :

| Quoi | Où | Perdre le seul exemplaire |
|---|---|---|
| Coffre d'autorité | poste opérateur | le domaine est perdu |
| Volume `astra-state` | gateway | registre et chaîne d'audit perdus |
| Clés de sécurité | vos poches | il en reste une autre — c'est le but |

Le coffre est chiffré : une copie hors ligne ne l'expose pas. Le volume Astra
contient la clé de service privée : traitez-le comme un secret.

La **tête de chaîne d'audit** est ce qui distingue une restauration légitime
d'un fork, et `astra run --expected-audit-head` est ce qui refuse le second.
`deploy.sh` la conserve dans `~/.helios/astra/audit-head`.

## Limite connue : retirer une clé ne rattrape pas les sauvegardes

`astra-signer remove` rescelle le corps du coffre sous la table de slots qu'il
laisse : le slot retiré, recollé depuis une sauvegarde, n'ouvre plus le fichier
courant. Mais une sauvegarde **antérieure** au retrait reste ouvrable par la clé
retirée, définitivement — c'est la situation de LUKS avec une phrase supprimée
depuis.

La réponse à un credential réellement compromis n'est donc pas un retrait de
slot, c'est une rotation de `CA-PQ`.

## Essais sur cible

Voir [testing/TESTING.md](testing/TESTING.md), sections « coffre d'autorité
Astra » et « domaine de confiance ». Rien de ce qui touche la clé de sécurité ne
s'exerce en WSL2 : aucun passthrough USB.

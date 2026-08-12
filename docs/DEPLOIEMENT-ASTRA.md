# Déployer Astra et amorcer un domaine de confiance

Guide opératoire de l'[ADR-008](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md). Il
décrit ce qui existe aujourd'hui et **nomme ce qui manque encore**, parce qu'un
guide qui laisse croire que la rotation fonctionne coûte une journée à celui
qui le suit.

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
le même. Le coffre d'autorité le mémorise à `astra-signer init` ; en changer
rend tous les key-slots inouvrables, définitivement, sans recours — la
spécification refuse explicitement toute phrase de passe de secours.

Choisissez un nom que vous garderez : `astra.helios.local` en interne, ou un nom
public si Astra sort. La **même** valeur ira à trois endroits : `astra-signer
init --rp-id`, `astra bootstrap --webauthn-rp-id`, `heliosd init-trust-domain
--webauthn-rp-id`.

## Prérequis

- La gateway tourne, et son identité de négociation existe déjà — c'est-à-dire
  que `heliosd init-key-negotiation` a été passé. Le registre décrit les leaves
  effectivement servies ; sans elles il n'y a rien à décrire.
- Un moteur de conteneur sur la gateway (`docker compose` ou `podman compose`).
- **Deux** clés de sécurité FIDO2 avec PIN configuré. Une seule suffit pour
  commencer : l'autorité restera « non amorcée » et le dira à chaque commande,
  jusqu'à l'enrôlement de la seconde.
- Le compagnon bâti sur la machine où la clé se branche :
  `cargo build --release -p astra-signer`. Sous Windows il demande un processus
  élevé — l'accès HID direct aux périphériques FIDO y est réservé aux processus
  élevés depuis Windows 10 1903.

## 1. Le coffre d'autorité, sur le poste opérateur

```sh
astra-signer init --rp-id astra.helios.local --label "YubiKey du bureau"
```

Génère `CA-PQ` (ML-DSA-87) et `CA-TLS`, les scelle sous un key-slot ouvert par
la clé branchée, et imprime :

- **CA-PQ publique**, base64 — l'ancre du domaine ;
- **trust_domain_id**, 32 hex ;
- l'empreinte du coffre, à noter pour reconnaître une sauvegarde.

Il annonce ensuite que l'autorité n'est **pas** amorcée : une clé sur les deux
exigées. C'est normal et c'est voulu.

Le coffre est à `~/.helios/astra/authority-vault.json` (ou `%APPDATA%` sous
Windows). **Sauvegardez-le.** Le perdre entièrement, c'est perdre le domaine ;
il est déjà chiffré, donc une copie hors ligne ne coûte rien.

Quand la seconde clé est en main :

```sh
astra-signer enrol --label "YubiKey de récupération"
astra-signer verify        # à faire avec chacune des deux, séparément
```

`enrol` demande d'abord la clé déjà enregistrée, puis la nouvelle : deux objets,
branchés un à la fois. Une troisième ou une quatrième clé plus tard, c'est la
même commande — rien ne distingue la seconde de la cinquième.

L'ADR ne tient le bootstrap pour fini qu'« après enregistrement **et essai** des
deux clés ». `verify` est cet essai : il ouvre les ancres, pas seulement le
slot.

## 2. Astra, sur la gateway

```sh
cp deploy/astra/env.example deploy/astra/.env   # puis le remplir
./scripts/deploy-astra.sh                        # hôte repris de deploy.sh
```

Le script construit l'image, la transfère, copie la configuration, puis
constate que le domaine n'est pas amorcé et imprime la commande exacte. Elle
ressemble à :

```sh
cd ~/astra && docker compose -f deploy/astra/compose.yaml \
  --env-file deploy/astra/.env run --rm astra bootstrap \
  --ca-public-key "<CA-PQ de l'étape 1>" \
  --trust-domain-id "<domaine de l'étape 1>" \
  --gateway-wireguard-public-key "$(sudo wg show helios0 public-key)" \
  --server-name "<sujet de la leaf PQ>" \
  --authority-url https://astra.helios.local \
  --webauthn-rp-id astra.helios.local
```

Le `server-name` est ce qui avait été passé à `heliosd init-key-negotiation
--server-name` : le sujet de la leaf PQ que vos clients épinglent.

Le bootstrap imprime la **clé de service** d'Astra et la **tête de chaîne
d'audit**. Reportez la tête dans `ASTRA_EXPECTED_AUDIT_HEAD`, puis relancez le
script : sans elle, une restauration de sauvegarde qui a divergé est reprise en
silence — deux histoires pour un domaine, et aucun moyen de savoir laquelle les
clients ont vue.

## 3. L'autre moitié du domaine, sur la gateway

```sh
sudo heliosd init-trust-domain \
  --trust-domain-id "<domaine>" \
  --ca-public-key "<CA-PQ>" \
  --astra-service-public-key "<clé de service imprimée à l'étape 2>" \
  --authority-url https://astra.helios.local \
  --webauthn-rp-id astra.helios.local
sudo systemctl restart heliosd
```

La commande n'ouvre aucun coffre et ne génère aucune clé. Tout ce qu'elle écrit
est public : les leaves que cette gateway sert déjà, relues sur disque, et les
ancres qu'on lui dit de croire. Elle tourne donc même TPM indisponible.

Le nom de serveur et la clé WireGuard ne sont **pas** des arguments : ils sont
relus dans la leaf PQ servie. Le registre doit décrire l'identité réellement
présentée, et deux champs qui doivent concorder sont deux champs qui peuvent
diverger — la divergence n'apparaîtrait qu'au premier staging, en refus ne
nommant ni l'un ni l'autre.

Au redémarrage, le journal dit `certificate lifecycle ready` au lieu de `no
certificate registry`.

## Sauvegardes

Trois objets, trois endroits, et aucun ne remplace un autre :

| Quoi | Où | Perdre le seul exemplaire |
|---|---|---|
| Coffre d'autorité | poste opérateur | le domaine est perdu |
| Volume `astra-state` | gateway | registre et chaîne d'audit perdus |
| Clés de sécurité | vos poches | il en reste une autre — c'est le but |

Le coffre est chiffré : une copie hors ligne ne l'expose pas. Le volume Astra
contient la clé de service privée : traitez-le comme un secret.

Notez la **tête de chaîne d'audit** à chaque changement notable. C'est elle qui
distingue une restauration légitime d'un fork, et `astra run
--expected-audit-head` est ce qui refuse le second.

## Limite connue : retirer une clé ne rattrape pas les sauvegardes

`astra-signer remove` rescelle le corps du coffre sous la table de slots qu'il
laisse : le slot retiré, recollé depuis une sauvegarde, n'ouvre plus le fichier
courant. Mais une sauvegarde **antérieure** au retrait reste ouvrable par la clé
retirée, définitivement — c'est la situation de LUKS avec une phrase supprimée
depuis.

La réponse à un credential réellement compromis n'est donc pas un retrait de
slot, c'est une rotation de `CA-PQ`.

## Essais sur cible

Voir [testing/TESTING.md](testing/TESTING.md), section « coffre d'autorité
Astra ». Rien de ce qui touche la clé de sécurité ne s'exerce en WSL2 : aucun
passthrough USB.

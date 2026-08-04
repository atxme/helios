# ADR 007 — Fenêtre de mise à jour TPM

**Statut** : accepté (2026-08-03).

**Portée** : survie de l'identité scellée d'une gateway à travers une mise à
jour du système d'exploitation qui déplace les PCR. Ne modifie **rien** au
scellement nominal — sélection PCR 0/4/7, gabarit de l'objet, chemin de
descellement, billet de rescellement, séquestre : tout reste en l'état. Cet ADR
ajoute un slot NV TPM indépendant et le comportement de démarrage qui le
consomme puis l'écrase.

## Contexte

Helios est livrée sur une machine Debian ordinaire, pas sur une image
d'appliance. Elle doit donc recevoir les correctifs de sécurité de son OS.
L'[ADR-003](ADR-003-MISES-A-JOUR-APPLICATIVES.md) §1 avait mis ce sujet hors
périmètre — « la mise à jour ne remplace ni rootfs, ni kernel, ni bootloader
[…] les PCR 0/4/7 ne changent donc pas ». C'est exact pour une mise à jour
*applicative* d'Helios ; ce n'est pas une réponse à `apt upgrade`.

### Ce que coûtait une mise à jour noyau

Les PCR ne sont étendus qu'au démarrage : `apt upgrade` ne casse rien sur une
machine en marche. La panne est différée au redémarrage suivant, et seulement si
la mise à jour a touché la chaîne de démarrage — `linux-image`, `shim`, `grub`,
une base Secure Boot, un firmware. Ce jour-là, en revanche, l'addition était
lourde :

1. le descellement échoue, aucun billet n'est présent, `enforce = true` : le
   démon ne démarre pas du tout ;
2. avec un billet valide, `provisioning::reseal` génère un **nouveau** secret.
   Les deux coffres deviennent illisibles. Celui de la clé WireGuard est couvert
   par le séquestre ; celui de l'identité de négociation ne l'est pas, et sa
   perte impose `init-key-negotiation --rotate`, donc un nouveau certificat, donc
   **le ré-enrôlement de tous les clients** qui l'épinglent.

Une mise à jour noyau coûtait le parc entier.

### La cause

Le rescellement est conçu pour réparer **après coup**, quand le secret est déjà
perdu ; il ne peut donc qu'en fabriquer un nouveau, et tout ce qui dépendait de
l'ancien meurt. Une mise à jour d'OS est la situation inverse : elle est
planifiée, et elle s'exécute sur une machine dont le secret est descellé et en
mémoire. C'est cette asymétrie que la décision exploite.

## Décision

### 1. Un slot NV protégé, à usage unique

Avant le redémarrage, `heliosd tpm prepare-update` écrit le **même** secret dans
un index NV distinct, sous une politique de lecture en trois clauses :

| Clause | Rôle |
|---|---|
| `PolicyPCR(0, 7)` | La sélection nominale privée de PCR 4 — celui que la mise à jour déplace légitimement. Substituer le firmware ou désactiver Secure Boot ferme ce chemin. |
| `PolicyNvWritten(true)` | L'index doit avoir été initialisé. Cette assertion porte bien sur l'entité autorisée : l'index NV lui-même. |
| `PolicyCommandCode(TPM2_NV_Read)` | La politique ne sert qu'à lire le payload NV. |

L'index autorise l'écriture par Owner, mais jamais la lecture par Owner : seule
la politique PCR 0/7 lit son contenu. L'écriture et la lecture passent par des
sessions salées et chiffrées. La révocation **écrase le payload dans le TPM** ;
le disque ne porte qu'un marqueur non secret (`deadline` et ancre du blob
nominal). Copier ou restaurer ce marqueur ne restaure donc pas le secret.

Ce choix évite un piège de `PolicyNvWritten` : cette assertion ne désigne aucun
index tiers. Elle ne peut pas faire dépendre l'`Unseal` d'un objet `KeyedHash`
de l'état d'un autre index ; elle ne s'applique correctement que lorsque
l'entité autorisée est l'index NV lui-même.

L'armement exige un descellement **nominal** de ce démarrage-ci. La fenêtre
transporte un verdict d'intégrité, elle n'en fabrique pas : armer depuis un
démarrage `Bypassed`, `Resealed` ou `Provisioned` est refusé.

Le marqueur est synchronisé sur disque **avant** l'écriture NV. Une erreur
d'armement est ambiguë — le TPM peut avoir exécuté la commande puis perdu sa
réponse — donc elle déclenche un écrasement compensatoire. Le marqueur n'est
supprimé que si cet écrasement est confirmé ; sinon il reste en place pour que
le timer puisse réessayer.

### 2. Ordre de démarrage

1. descellement nominal PCR 0/4/7 — **toujours d'abord**. S'il réussit, une
   fenêtre restée armée est révoquée sur-le-champ : une mise à jour qui n'a
   finalement rien déplacé ne doit pas laisser un objet vivant derrière elle ;
2. `UnsealPolicyFail` et fenêtre armée : contrôle du marqueur, lecture du slot
   NV, **rescellement du même secret** sur les PCR 0/4/7 courants, puis
   écrasement NV et suppression du marqueur →
   `BootDecision::WindowResealed` ;
3. une fenêtre confirmée absente, expirée, incohérente ou fermée par PCR 0/7
   est d'abord écrasée, puis seulement le chemin billet est envisagé. Une
   panne d'E/S, de TPM ou de rescellement est fatale : elle ne prouve pas que
   l'ancien secret a disparu et ne doit jamais autoriser la création d'un
   second secret concurrent.

L'ordre des écritures en 2 est un invariant : le nouveau blob nominal est écrit,
`fsync` compris sur le fichier et son répertoire, **avant** l'écrasement NV. Un
rescellement qui échoue laisse la fenêtre utilisable, donc une nouvelle tentative
possible dans le même cycle de démarrage ; le démon refuse de démarrer
entre-temps. Une erreur d'écrasement après rescellement est fatale et ne retombe
jamais sur le billet : ce dernier fabriquerait un nouveau secret alors que le bon
blob est déjà en place.

`TpmState.version`, le compteur anti-rejeu des billets, n'est pas touché : la
fenêtre ne consomme aucune version et n'interfère pas avec l'anti-rollback.

### 3. Ce que la fenêtre ne couvre pas

**Limite connue.** Un attaquant disposant de l'accès physique qui, *pendant* que
la fenêtre est ouverte, démarre un autre OS signé Secure Boot sur cette machine
descelle le secret. Le TPM ne sait pas distinguer « le prochain démarrage » de
« le démarrage de l'attaquant » : il faudrait `TPM2_PolicyCounterTimer` sur
`resetCount`, que `tss-esapi` 7.7 n'expose pas (`// Missing function:
PolicyCounterTimer`). Y accéder par les liaisons brutes `tss2_esys` supprimerait
ce résidu, au prix d'une surface `unsafe` et d'un chemin hors de l'API typée de
la bibliothèque. Cet arbitrage est reporté et reste conditionné aux mesures du
lot 0 ci-dessous.

Deux réductions d'exposition en attendant :

* `--reboot` réduit la fenêtre à la durée d'un redémarrage ;
* `helios-update-window.timer` lit le marqueur non secret et écrase le payload
  NV si le redémarrage n'a pas eu lieu.

Le timer est un garde-fou opérationnel, pas une borne cryptographique : un
attaquant qui contrôle le disque ou l'horloge pendant la fenêtre peut aussi
altérer le marqueur ou empêcher l'unité de s'exécuter. La seule réduction
robuste disponible avec cette politique reste donc de redémarrer immédiatement.

La lecture hostile n'est **pas détectable** : `TPM2_NV_Read` ne sait pas lire et
effacer atomiquement. Un attaquant peut copier le secret sans modifier l'index,
puis laisser le démarrage légitime réussir. `TPM2_PolicyCounterTimer` sur
`resetCount`, ou un primitif matériel équivalent de lecture destructive,
fermerait cette limite ; jusque-là, `--reboot` est obligatoire en exploitation.

**Hors périmètre également** : une mise à jour qui déplace PCR 0 ou 7 — firmware,
base Secure Boot. La fenêtre ne s'ouvrira pas et le démarrage retombe sur billet
et séquestre, comme aujourd'hui. C'est le cas rare ; le noyau et le bootloader
sont le cas fréquent.

### 4. Ce qui reste à mesurer sur la cible

Rien de ce qui précède ne se prouve en WSL2. Trois mesures conditionnent la
valeur réelle du dispositif, et doivent être relevées avant de s'en remettre à
lui en production ([TESTING.md](../testing/TESTING.md)) :

1. la présence d'un TPM et de l'espace NV ;
2. **l'état de Secure Boot** — désactivé, PCR 7 ne dit plus grand-chose et la
   clause qui borne la fenêtre perd l'essentiel de sa portée ;
3. le déplacement effectif de PCR 4 lors d'une mise à jour noyau, qui dépend de
   la chaîne de démarrage réelle (shim présent ou non, module TPM de GRUB).

## Conséquences

Une mise à jour noyau redevient une opération ordinaire : le secret survit, donc
`wg-key.sealed`, l'identité de négociation et la table des PSK statiques
survivent, et aucun client n'est ré-enrôlé. Le billet de rescellement reste ce
qu'il était — le chemin de récupération pour un changement de PCR **subi**, non
planifié.

L'affirmation de l'ADR-003 §1 selon laquelle l'administration de l'OS est hors
périmètre n'est plus vraie de la partie qui touche au scellement. Elle reste
vraie du reste : Helios ne distribue toujours pas de noyau ni de rootfs.

Le manque que cette décision **ne comble pas** : l'identité de négociation reste
sans séquestre. Pour un changement de PCR subi, sa perte impose toujours une
rotation et le ré-enrôlement du parc. C'est un lot distinct, sur le patron de
`gateway_key::write_escrow`.
